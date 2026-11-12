# Tenable Nessus Audit Engine: Architecture, Variables, Keys & Matching Engine Specification

**Author:** kakaxh1 (Bhavy Morvadiya)  
**Standard:** Tenable Compliance Engine Specification (Plugins 21745, 24764, 84239, 21156)  
**Encoding & Syntax Rules:** Strict ASCII, standard hyphens (-), valid XML tokens, zero smart quotes  

---

## 1. System Execution Model & Flow

When Tenable Nessus performs a compliance check (live SSH/SNMP or offline configuration file), the evaluation follows a 5-stage pipeline:

```
[Target Config / Device CLI]
             |
             v
   Stage 1: Pre-Condition Check (<if><condition><item>)
             |
             +---> If FALSE ---> Route to <else> (or terminate if no <else>)
             |
             +---> If TRUE  ---> Enter <then> block
                                      |
                                      v
   Stage 2: Context Isolation (context: "...")
             |
             v
   Stage 3: Line Extraction (regex: "..." / item: "...")
             |
             v
   Stage 4: Compliance Validation (expect: "..." / not_equal: YES)
             |
             v
   Stage 5: Result Generation (PASSED / WARNING / FAILED / ERROR)
```

---

## 2. Variables: Definition, Scope & Runtime Substitution

Variables allow security policies to be parameterized. Instead of hardcoding environment-specific IP addresses, hostnames, or password lengths, variables let administrators enter values via the Nessus Web UI or API.

### 2.1 Variable Declaration Syntax

Variables must be declared at the top of the `.audit` file, immediately following the `<group_policy>` opening tag:

```xml
<variable>
  name: "NTP_SERVER_PRIMARY"
  default: "10.123.32.1"
  description: "Enterprise Primary NTP Server IP"
  info: "IP address of the authorized primary NTP time source."
</variable>

<variable>
  name: "MIN_PASSWORD_LENGTH"
  default: "12"
  description: "Minimum Administrative Password Length"
  info: "Minimum number of characters required by corporate password policy."
</variable>
```

### 2.2 Variable Fields Reference

| Field | Required | Description | Example |
| :--- | :--- | :--- | :--- |
| `name:` | Yes | Unique variable identifier. Must use uppercase alphanumeric and underscore characters. | `name: "SYSLOG_SERVER_IP"` |
| `default:` | Yes | Default fallback value if the user provides no input. | `default: "192.168.1.50"` |
| `description:` | Yes | The prompt label displayed in the Nessus UI scan configuration screen. | `description: "Enter SIEM IP"` |
| `info:` | No | Help tooltip text explaining the policy requirement. | `info: "Must be a routable IP."` |

### 2.3 Variable Substitution Syntax (`@VARIABLE_NAME@`)

At runtime, Nessus replaces every instance of `@VARIABLE_NAME@` with the user-defined value (or default) across **all** fields (`description`, `info`, `context`, `regex`, `expect`):

```xml
<custom_item>
  type: CONFIG_CHECK
  description: "Verify NTP Server is configured to @NTP_SERVER_PRIMARY@"
  info: "NTP synchronization ensures chronological audit log integrity."
  solution: "Configure: set server @NTP_SERVER_PRIMARY@"
  reference: "NIST-800-53|AU-8"
  severity: MEDIUM
  context: "config system ntp"
  regex: "set server [0-9.]+"
  expect: "set server \"@NTP_SERVER_PRIMARY@\""
</custom_item>
```

---

## 3. Comprehensive Key & Value Reference

Each `<item>` and `<custom_item>` is defined by specific key-value directives. Below is the definitive catalog of all supported keys and their exact behavior.

---

### 3.1 Structural & Metadata Keys

#### `type:` (Required)
Defines the compliance check plugin engine to execute.

| Target Platform | Valid `type:` Values |
| :--- | :--- |
| **Cisco / Network** | `CONFIG_CHECK`, `BANNER_CHECK`, `VERSION_CHECK` |
| **Fortinet FortiOS** | `CONFIG_CHECK`, `VERSION_CHECK` |
| **Unix / Linux** | `FILE_CONTENT_CHECK`, `FILE_CHECK`, `CMD_EXEC`, `RPM_CHECK`, `PKG_CHECK`, `PROCESS_CHECK` |
| **Windows** | `REGISTRY_SETTING`, `PASSWORD_POLICY`, `USER_RIGHTS_POLICY`, `AUDIT_POLICY` |

> **Warning:** Check types like `CONFIG_CHECK_NOT` do not exist and will crash the parser.

#### `description:` (Required)
The formal title of the control. Displayed as the finding header in Nessus scan reports.
- **Best Practice:** Include the Control ID and action verb:
  `description: "NIMF_WIFI_01 Enforce 802.11ax High-Efficiency Standard"`

#### `info:` (Recommended)
Explains the security rationale, risk, and technical justification for the control.

#### `solution:` (Recommended)
Exact, copy-pasteable CLI commands or configuration file edits required to achieve compliance.

#### `reference:` (Optional)
Standard mapping tags separated by commas.
- Format: `FRAMEWORK|CONTROL_NUMBER`
- Example: `reference: "CIS-CSCv8|4.1,NIST-800-53|AC-17,PCI-DSSv4|2.2.1"`

#### `see_also:` (Optional)
Web link to official CIS benchmarks, vendor documentation, or security advisories.

#### `severity:` (Required)
Controls finding classification in dashboards and reports:
- `PASSED`: Displayed only when the check passes (Informational).
- `LOW`: Minor security hardening suggestion.
- `MEDIUM`: Standard compliance deviation (e.g. timeout values, non-standard banners).
- `HIGH`: Major security risk (e.g. unencrypted management, default credentials).
- `CRITICAL`: Immediate compromise vector (e.g. Telnet enabled, blank root password).

---

### 3.2 Navigation & Scope Isolation Keys

#### `context:`
Defines configuration boundary isolation in hierarchical CLI structures (Cisco, FortiGate, Arista, Juniper).

- **How It Works:**
  1. The engine scans the configuration top-to-bottom for a block header matching `context:`.
  2. Once found, it creates an isolated virtual buffer containing only lines belonging to that block, up to the closing boundary (`end`, `next`, `exit`, `!`).
  3. All subsequent `regex:` and `expect:` checks operate **strictly within this isolated buffer**.
- **Example (FortiOS):**
  ```xml
  context: "config wireless-controller wtp"
  ```
- **Example (Cisco):**
  ```xml
  context: "line vty [0-9]+ [0-9]+"
  ```
- **Platform Scope:** Valid in `Cisco`, `FortiGate`, `Extreme`. **Illegal** in `Unix` and `Windows`.

#### `match_all:` (`YES` / `NO`)
Controls multi-block evaluation when a `context:` matches multiple sections.

- **Default:** `NO`
- **When `match_all: YES`:**
  Every single matching block in the entire configuration must satisfy the `expect:` condition. If 23 switch interfaces are compliant but 1 is non-compliant, the entire control **FAILS**.
- **When `match_all: NO`:**
  If at least one matching block satisfies the condition, the check passes.
- **Example:**
  ```xml
  <custom_item>
    type: CONFIG_CHECK
    description: "Ensure port-security is enabled on all access interfaces"
    context: "interface GigabitEthernet[0-9/]+"
    match_all: YES
    regex: "switchport port-security"
    expect: "^\\s*switchport port-security$"
  </custom_item>
  ```

#### `required:` (`YES` / `NO`)
Determines behavior if the `context:` block does not exist in the configuration.

- **Default:** `YES`
- **When `required: YES`:** If the block is absent, Nessus flags a compliance failure.
- **When `required: NO`:** If the block is absent, Nessus treats the control as Not Applicable (skips evaluation without failing).

---

### 3.3 Extraction, Matching & Validation Keys

#### `item:` vs `regex:` vs `expect:`

The relationship between these three keys is the most critical concept in Nessus audit authoring:

```
[Isolated Context Buffer]
           |
           v
  Filter by 'item:' (Optional substring line filter)
           |
           v
  Capture by 'regex:' (PCRE pattern matching specific target line)
           |
           v
  Validate with 'expect:' (Exact string or PCRE comparison)
           |
           v
  [Compliant or Non-Compliant]
```

#### Detailed Comparison:

| Key | Purpose | Matching Engine Behavior | Supported Platforms |
| :--- | :--- | :--- | :--- |
| `item:` | Substring filter | Retains only lines containing this substring before running regex. | Cisco, Brocade |
| `regex:` | Extraction filter | Evaluates a PCRE regex against context lines. If no line matches `regex:`, the item fails as "Parameter Missing". | All platforms |
| `expect:` | Verification test | Compares extracted line(s) against this required value. If it matches, check passes; if not, check fails. | All platforms |

#### `not_equal:` (`YES` / `NO`)
Inverts the evaluation logic of `expect:`.

- **Default:** `NO`
- **When `not_equal: NO`:** Line must **MATCH** `expect:` to pass.
- **When `not_equal: YES`:** Line must **NOT MATCH** `expect:` to pass. If the extracted line matches `expect:`, Nessus flags a compliance violation.
- **Example (Detecting insecure default community string):**
  ```xml
  <custom_item>
    type: CONFIG_CHECK
    description: "Ensure default SNMP community string 'public' is not used"
    context: "config system snmp community"
    regex: "set name "
    expect: "set name \"public\""
    not_equal: YES
    severity: HIGH
  </custom_item>
  ```

---

## 4. How the Matching Engine Evaluates Logic

### Pattern 1: Exact String Equality
Checking that an administrative setting is configured to a specific static value.

```xml
context: "config system global"
regex: "set admin-sport [0-9]+"
expect: "set admin-sport 8443"
```
- **Evaluation:**
  1. Finds `config system global`.
  2. Extracts the line containing `set admin-sport`.
  3. If line is `set admin-sport 8443` -> **PASS**.
  4. If line is `set admin-sport 443` -> **FAIL**.
  5. If line is not found -> **FAIL (Missing Parameter)**.

---

### Pattern 2: Regex Sub-String / Range Matching
Checking that a timeout value is within an acceptable range (e.g. idle timeout between 1 and 15 minutes).

```xml
context: "config system global"
regex: "set admintimeout [0-9]+"
expect: "set admintimeout ([1-9]|1[0-5])$"
```
- **Evaluation:**
  Matches any timeout from 1 to 15. If timeout is 20 or 60, evaluation fails.

---

### Pattern 3: Negative Matching / Parameter Absence (Excluding 802.11b)
Ensuring that legacy 802.11b rates are excluded from wireless band settings.

```xml
context: "config radio-1"
regex: "set band [^\n]+"
expect: "^set band (?!.*802\\.11b).*$"
```
- **Evaluation:**
  - `fotiap.cfg` value: `set band 802.11b 802.11g 802.11n-2G 802.11ax-2G`
  - The negative lookahead `(?!.*802\\.11b)` detects `802.11b` and fails the check.
  - Remediated value: `set band 802.11g 802.11n-2G 802.11ax-2G` passes clean.

---

### Pattern 4: Pre-Flight Environment Detection (`<if><condition><item>`)
Ensuring custom items run **only** if the target device matches the required profile.

```xml
<if>
  <condition type:"AND">
    <item>
      type: CONFIG_CHECK
      description: "Detect FortiAP WTP Configuration"
      context: "config wireless-controller wtp"
      regex: "edit \"[^\"]+\""
      expect: "edit "
    </item>
  </condition>

  <then>
    # Custom items evaluate only if condition is TRUE
  </then>

  <else>
    <custom_item>
      type: CONFIG_CHECK
      description: "Target configuration is not a FortiAP WTP"
      info: "Skipping FortiAP baseline checks because WTP table was not found."
      severity: LOW
    </custom_item>
  </else>
</if>
```

---

## 5. Master Template: Ready-to-Use Boilerplate

Below is a complete, syntactically verified boilerplate template demonstrating variables, pre-conditions, context navigation, and positive and negative checks:

```xml
# This script is Copyright (C) 2026 kakaxh1 (Bhavy Morvadiya).

<check_type:"FortiGate">

<group_policy:"NIMF Enterprise Baseline">

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

